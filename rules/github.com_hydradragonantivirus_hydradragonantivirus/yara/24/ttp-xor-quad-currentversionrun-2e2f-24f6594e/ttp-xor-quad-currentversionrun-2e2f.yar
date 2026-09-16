rule TTP_XOR_QUAD_CurrentVersionRun_2e2f {
  strings:
    $key_2e2f = { 7d 40 [2] 59 4e [2] 72 62 [2] 5c 40 [2] 48 5b [2] 47 41 [2] 59 5c [2] 5b 5d [2] 40 5b [2] 5c 5c [2] 40 73 }

  condition:
    any of them
}