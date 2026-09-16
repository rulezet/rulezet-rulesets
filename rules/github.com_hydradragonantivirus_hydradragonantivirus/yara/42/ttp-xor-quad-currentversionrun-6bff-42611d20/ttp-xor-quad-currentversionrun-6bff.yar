rule TTP_XOR_QUAD_CurrentVersionRun_6bff {
  strings:
    $key_6bff = { 38 90 [2] 1c 9e [2] 37 b2 [2] 19 90 [2] 0d 8b [2] 02 91 [2] 1c 8c [2] 1e 8d [2] 05 8b [2] 19 8c [2] 05 a3 }

  condition:
    any of them
}