rule TTP_XOR_QUAD_CurrentVersionRun_e20f {
  strings:
    $key_e20f = { b1 60 [2] 95 6e [2] be 42 [2] 90 60 [2] 84 7b [2] 8b 61 [2] 95 7c [2] 97 7d [2] 8c 7b [2] 90 7c [2] 8c 53 }

  condition:
    any of them
}