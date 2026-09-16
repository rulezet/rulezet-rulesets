rule TTP_XOR_QUAD_CurrentVersionRun_027e {
  strings:
    $key_027e = { 51 11 [2] 75 1f [2] 5e 33 [2] 70 11 [2] 64 0a [2] 6b 10 [2] 75 0d [2] 77 0c [2] 6c 0a [2] 70 0d [2] 6c 22 }

  condition:
    any of them
}