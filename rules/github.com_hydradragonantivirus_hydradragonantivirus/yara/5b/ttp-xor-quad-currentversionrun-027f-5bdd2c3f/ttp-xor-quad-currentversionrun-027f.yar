rule TTP_XOR_QUAD_CurrentVersionRun_027f {
  strings:
    $key_027f = { 51 10 [2] 75 1e [2] 5e 32 [2] 70 10 [2] 64 0b [2] 6b 11 [2] 75 0c [2] 77 0d [2] 6c 0b [2] 70 0c [2] 6c 23 }

  condition:
    any of them
}