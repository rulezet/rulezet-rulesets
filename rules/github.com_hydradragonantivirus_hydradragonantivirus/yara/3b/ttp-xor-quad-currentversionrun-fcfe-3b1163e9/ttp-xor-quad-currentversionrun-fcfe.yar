rule TTP_XOR_QUAD_CurrentVersionRun_fcfe {
  strings:
    $key_fcfe = { af 91 [2] 8b 9f [2] a0 b3 [2] 8e 91 [2] 9a 8a [2] 95 90 [2] 8b 8d [2] 89 8c [2] 92 8a [2] 8e 8d [2] 92 a2 }

  condition:
    any of them
}