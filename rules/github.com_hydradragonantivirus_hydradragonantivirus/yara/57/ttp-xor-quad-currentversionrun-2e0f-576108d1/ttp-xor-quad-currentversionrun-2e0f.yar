rule TTP_XOR_QUAD_CurrentVersionRun_2e0f {
  strings:
    $key_2e0f = { 7d 60 [2] 59 6e [2] 72 42 [2] 5c 60 [2] 48 7b [2] 47 61 [2] 59 7c [2] 5b 7d [2] 40 7b [2] 5c 7c [2] 40 53 }

  condition:
    any of them
}