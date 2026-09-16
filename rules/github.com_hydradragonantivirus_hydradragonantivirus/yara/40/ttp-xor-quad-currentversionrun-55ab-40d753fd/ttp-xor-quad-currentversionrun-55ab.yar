rule TTP_XOR_QUAD_CurrentVersionRun_55ab {
  strings:
    $key_55ab = { 06 c4 [2] 22 ca [2] 09 e6 [2] 27 c4 [2] 33 df [2] 3c c5 [2] 22 d8 [2] 20 d9 [2] 3b df [2] 27 d8 [2] 3b f7 }

  condition:
    any of them
}