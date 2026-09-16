rule TTP_XOR_QUAD_CurrentVersionRun_371c {
  strings:
    $key_371c = { 64 73 [2] 40 7d [2] 6b 51 [2] 45 73 [2] 51 68 [2] 5e 72 [2] 40 6f [2] 42 6e [2] 59 68 [2] 45 6f [2] 59 40 }

  condition:
    any of them
}