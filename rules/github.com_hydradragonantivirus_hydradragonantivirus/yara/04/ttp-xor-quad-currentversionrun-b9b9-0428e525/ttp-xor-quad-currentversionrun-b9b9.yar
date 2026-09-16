rule TTP_XOR_QUAD_CurrentVersionRun_b9b9 {
  strings:
    $key_b9b9 = { ea d6 [2] ce d8 [2] e5 f4 [2] cb d6 [2] df cd [2] d0 d7 [2] ce ca [2] cc cb [2] d7 cd [2] cb ca [2] d7 e5 }

  condition:
    any of them
}