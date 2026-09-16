rule TTP_XOR_QUAD_CurrentVersionRun_023b {
  strings:
    $key_023b = { 51 54 [2] 75 5a [2] 5e 76 [2] 70 54 [2] 64 4f [2] 6b 55 [2] 75 48 [2] 77 49 [2] 6c 4f [2] 70 48 [2] 6c 67 }

  condition:
    any of them
}