rule GS_SDK_challenge_response_algorithm__Soldier_of_Anarchy__key__8_byt_STR_32_ {
  strings:
    $a0 = "0AB3F935936211D19A2B080000300512"

  condition:
    $a0
}