rule TTP_XOR_QUAD_CurrentVersionRun_570f {
  strings:
    $key_570f = { 04 60 [2] 20 6e [2] 0b 42 [2] 25 60 [2] 31 7b [2] 3e 61 [2] 20 7c [2] 22 7d [2] 39 7b [2] 25 7c [2] 39 53 }

  condition:
    any of them
}