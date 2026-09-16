rule TTP_XOR_QUAD_CurrentVersionRun_621c {
  strings:
    $key_621c = { 31 73 [2] 15 7d [2] 3e 51 [2] 10 73 [2] 04 68 [2] 0b 72 [2] 15 6f [2] 17 6e [2] 0c 68 [2] 10 6f [2] 0c 40 }

  condition:
    any of them
}