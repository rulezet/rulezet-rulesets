rule TTP_XOR_QUAD_CurrentVersionRun_7abe {
  strings:
    $key_7abe = { 29 d1 [2] 0d df [2] 26 f3 [2] 08 d1 [2] 1c ca [2] 13 d0 [2] 0d cd [2] 0f cc [2] 14 ca [2] 08 cd [2] 14 e2 }

  condition:
    any of them
}