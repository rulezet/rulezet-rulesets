rule TTP_XOR_QUAD_CurrentVersionRun_feff {
  strings:
    $key_feff = { ad 90 [2] 89 9e [2] a2 b2 [2] 8c 90 [2] 98 8b [2] 97 91 [2] 89 8c [2] 8b 8d [2] 90 8b [2] 8c 8c [2] 90 a3 }

  condition:
    any of them
}