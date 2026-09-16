rule TTP_XOR_QUAD_CurrentVersionRun_135c {
  strings:
    $key_135c = { 40 33 [2] 64 3d [2] 4f 11 [2] 61 33 [2] 75 28 [2] 7a 32 [2] 64 2f [2] 66 2e [2] 7d 28 [2] 61 2f [2] 7d 00 }

  condition:
    any of them
}