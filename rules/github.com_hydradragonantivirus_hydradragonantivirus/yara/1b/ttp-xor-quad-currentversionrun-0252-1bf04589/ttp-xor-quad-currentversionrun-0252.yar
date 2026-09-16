rule TTP_XOR_QUAD_CurrentVersionRun_0252 {
  strings:
    $key_0252 = { 51 3d [2] 75 33 [2] 5e 1f [2] 70 3d [2] 64 26 [2] 6b 3c [2] 75 21 [2] 77 20 [2] 6c 26 [2] 70 21 [2] 6c 0e }

  condition:
    any of them
}