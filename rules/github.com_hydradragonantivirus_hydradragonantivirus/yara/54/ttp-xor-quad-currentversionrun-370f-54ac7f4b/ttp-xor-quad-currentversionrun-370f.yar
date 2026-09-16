rule TTP_XOR_QUAD_CurrentVersionRun_370f {
  strings:
    $key_370f = { 64 60 [2] 40 6e [2] 6b 42 [2] 45 60 [2] 51 7b [2] 5e 61 [2] 40 7c [2] 42 7d [2] 59 7b [2] 45 7c [2] 59 53 }

  condition:
    any of them
}