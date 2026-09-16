rule TTP_XOR_QUAD_CurrentVersionRun_fcff {
  strings:
    $key_fcff = { af 90 [2] 8b 9e [2] a0 b2 [2] 8e 90 [2] 9a 8b [2] 95 91 [2] 8b 8c [2] 89 8d [2] 92 8b [2] 8e 8c [2] 92 a3 }

  condition:
    any of them
}