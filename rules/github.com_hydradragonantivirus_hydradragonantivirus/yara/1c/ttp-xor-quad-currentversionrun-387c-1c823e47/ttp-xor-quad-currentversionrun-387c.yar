rule TTP_XOR_QUAD_CurrentVersionRun_387c {
  strings:
    $key_387c = { 6b 13 [2] 4f 1d [2] 64 31 [2] 4a 13 [2] 5e 08 [2] 51 12 [2] 4f 0f [2] 4d 0e [2] 56 08 [2] 4a 0f [2] 56 20 }

  condition:
    any of them
}