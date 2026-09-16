rule GS_SDK_challenge_response_algorithm_default_key__8_byt_STR_32_ {
  strings:
    $a0 = "3b8dd8995f7c40a9a5c5b7dd5b481341"

  condition:
    $a0
}