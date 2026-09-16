rule frat_executable {
  meta:
    author = "jeFF0Falltrades"
    ref    = "https://twitter.com/jeFF0Falltrades/status/1270709679375646720"

  strings:
    $str_path_0   = "FRat\\\\Short-Port" wide ascii
    $str_path_1   = "FRatv8\\\\Door\\\\Stub" wide ascii
    $str_path_2   = "snapshot\\\\Stub\\\\V1.js" wide ascii
    $str_sails    = "sails.io" wide ascii
    $str_crypto   = "CRYPTOGAMS by <appro@openssl.org>" wide ascii
    $str_socketio = "socket.io-client" wide ascii

  condition:
    3 of them
}