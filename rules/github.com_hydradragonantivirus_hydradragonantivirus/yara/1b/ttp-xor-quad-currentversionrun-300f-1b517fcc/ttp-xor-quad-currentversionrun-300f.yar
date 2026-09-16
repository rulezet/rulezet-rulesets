rule TTP_XOR_QUAD_CurrentVersionRun_300f {
  strings:
    $key_300f = { 63 60 [2] 47 6e [2] 6c 42 [2] 42 60 [2] 56 7b [2] 59 61 [2] 47 7c [2] 45 7d [2] 5e 7b [2] 42 7c [2] 5e 53 }

  condition:
    any of them
}