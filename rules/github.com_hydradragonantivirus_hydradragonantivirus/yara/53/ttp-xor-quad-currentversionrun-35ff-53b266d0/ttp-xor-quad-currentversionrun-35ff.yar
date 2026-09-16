rule TTP_XOR_QUAD_CurrentVersionRun_35ff {
  strings:
    $key_35ff = { 66 90 [2] 42 9e [2] 69 b2 [2] 47 90 [2] 53 8b [2] 5c 91 [2] 42 8c [2] 40 8d [2] 5b 8b [2] 47 8c [2] 5b a3 }

  condition:
    any of them
}