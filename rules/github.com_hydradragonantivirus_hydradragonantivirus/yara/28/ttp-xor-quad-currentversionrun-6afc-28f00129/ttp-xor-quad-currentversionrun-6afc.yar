rule TTP_XOR_QUAD_CurrentVersionRun_6afc {
  strings:
    $key_6afc = { 39 93 [2] 1d 9d [2] 36 b1 [2] 18 93 [2] 0c 88 [2] 03 92 [2] 1d 8f [2] 1f 8e [2] 04 88 [2] 18 8f [2] 04 a0 }

  condition:
    any of them
}