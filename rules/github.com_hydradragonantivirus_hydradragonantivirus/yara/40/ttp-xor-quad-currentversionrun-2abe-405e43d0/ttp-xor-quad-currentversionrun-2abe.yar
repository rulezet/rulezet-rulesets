rule TTP_XOR_QUAD_CurrentVersionRun_2abe {
  strings:
    $key_2abe = { 79 d1 [2] 5d df [2] 76 f3 [2] 58 d1 [2] 4c ca [2] 43 d0 [2] 5d cd [2] 5f cc [2] 44 ca [2] 58 cd [2] 44 e2 }

  condition:
    any of them
}