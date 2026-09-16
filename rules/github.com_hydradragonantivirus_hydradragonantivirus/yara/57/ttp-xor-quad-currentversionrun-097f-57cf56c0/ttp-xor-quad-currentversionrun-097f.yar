rule TTP_XOR_QUAD_CurrentVersionRun_097f {
  strings:
    $key_097f = { 5a 10 [2] 7e 1e [2] 55 32 [2] 7b 10 [2] 6f 0b [2] 60 11 [2] 7e 0c [2] 7c 0d [2] 67 0b [2] 7b 0c [2] 67 23 }

  condition:
    any of them
}