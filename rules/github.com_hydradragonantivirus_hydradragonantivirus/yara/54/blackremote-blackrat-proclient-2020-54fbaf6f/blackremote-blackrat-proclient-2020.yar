rule blackremote_blackrat_proclient_2020 {
  meta:
    author = "jeFF0Falltrades"
    ref    = "https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/"

  strings:
    $str_0  = "K:\\5.0\\Black Server 5.0\\BlackServer\\bin\\Release\\BlackRATServerM.pdb" wide ascii nocase
    $str_1  = "BlackRATServerM.pdb" wide ascii nocase
    $str_2  = "RATTypeBinder" wide ascii nocase
    $str_3  = "ProClient.dll" wide ascii nocase
    $str_4  = "Clientx.dll" wide ascii nocase
    $str_5  = "FileMelting" wide ascii nocase
    $str_6  = "Foxmail.url.mailto\\Shell\\open\\command" wide ascii nocase
    $str_7  = "SetRemoteDesktopQuality" wide ascii nocase
    $str_8  = "RecoverChrome" wide ascii nocase
    $str_9  = "RecoverFileZilla" wide ascii nocase
    $str_10 = "RemoteAudioGetInfo" wide ascii nocase

  condition:
    4 of them
}