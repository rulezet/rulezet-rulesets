rule TTP_XOR_QUAD_CurrentVersionRun_2e7f {
  strings:
    $key_2e7f = { 7d 10 [2] 59 1e [2] 72 32 [2] 5c 10 [2] 48 0b [2] 47 11 [2] 59 0c [2] 5b 0d [2] 40 0b [2] 5c 0c [2] 40 23 }

  condition:
    any of them
}