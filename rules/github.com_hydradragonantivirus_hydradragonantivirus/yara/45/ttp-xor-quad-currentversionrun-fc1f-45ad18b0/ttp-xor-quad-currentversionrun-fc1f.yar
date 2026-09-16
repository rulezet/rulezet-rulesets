rule TTP_XOR_QUAD_CurrentVersionRun_fc1f {
  strings:
    $key_fc1f = { af 70 [2] 8b 7e [2] a0 52 [2] 8e 70 [2] 9a 6b [2] 95 71 [2] 8b 6c [2] 89 6d [2] 92 6b [2] 8e 6c [2] 92 43 }

  condition:
    any of them
}