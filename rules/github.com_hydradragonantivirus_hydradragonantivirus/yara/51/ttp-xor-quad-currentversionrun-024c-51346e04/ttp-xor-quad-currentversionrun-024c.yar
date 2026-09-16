rule TTP_XOR_QUAD_CurrentVersionRun_024c {
  strings:
    $key_024c = { 51 23 [2] 75 2d [2] 5e 01 [2] 70 23 [2] 64 38 [2] 6b 22 [2] 75 3f [2] 77 3e [2] 6c 38 [2] 70 3f [2] 6c 10 }

  condition:
    any of them
}