rule TTP_XOR_QUAD_CurrentVersionRun_e55c {
  strings:
    $key_e55c = { b6 33 [2] 92 3d [2] b9 11 [2] 97 33 [2] 83 28 [2] 8c 32 [2] 92 2f [2] 90 2e [2] 8b 28 [2] 97 2f [2] 8b 00 }

  condition:
    any of them
}