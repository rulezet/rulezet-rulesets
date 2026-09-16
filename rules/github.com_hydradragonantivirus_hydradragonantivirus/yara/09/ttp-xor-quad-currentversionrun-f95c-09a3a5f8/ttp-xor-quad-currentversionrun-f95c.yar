rule TTP_XOR_QUAD_CurrentVersionRun_f95c {
  strings:
    $key_f95c = { aa 33 [2] 8e 3d [2] a5 11 [2] 8b 33 [2] 9f 28 [2] 90 32 [2] 8e 2f [2] 8c 2e [2] 97 28 [2] 8b 2f [2] 97 00 }

  condition:
    any of them
}