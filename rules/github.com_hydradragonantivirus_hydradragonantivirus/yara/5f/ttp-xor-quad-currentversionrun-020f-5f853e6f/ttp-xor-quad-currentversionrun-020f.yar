rule TTP_XOR_QUAD_CurrentVersionRun_020f {
  strings:
    $key_020f = { 51 60 [2] 75 6e [2] 5e 42 [2] 70 60 [2] 64 7b [2] 6b 61 [2] 75 7c [2] 77 7d [2] 6c 7b [2] 70 7c [2] 6c 53 }

  condition:
    any of them
}