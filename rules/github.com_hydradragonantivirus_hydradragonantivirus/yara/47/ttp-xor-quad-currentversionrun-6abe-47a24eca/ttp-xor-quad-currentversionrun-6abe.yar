rule TTP_XOR_QUAD_CurrentVersionRun_6abe {
  strings:
    $key_6abe = { 39 d1 [2] 1d df [2] 36 f3 [2] 18 d1 [2] 0c ca [2] 03 d0 [2] 1d cd [2] 1f cc [2] 04 ca [2] 18 cd [2] 04 e2 }

  condition:
    any of them
}