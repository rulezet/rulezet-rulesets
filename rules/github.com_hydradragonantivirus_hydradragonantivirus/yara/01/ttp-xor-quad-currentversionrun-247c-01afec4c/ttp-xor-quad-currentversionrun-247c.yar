rule TTP_XOR_QUAD_CurrentVersionRun_247c {
  strings:
    $key_247c = { 77 13 [2] 53 1d [2] 78 31 [2] 56 13 [2] 42 08 [2] 4d 12 [2] 53 0f [2] 51 0e [2] 4a 08 [2] 56 0f [2] 4a 20 }

  condition:
    any of them
}