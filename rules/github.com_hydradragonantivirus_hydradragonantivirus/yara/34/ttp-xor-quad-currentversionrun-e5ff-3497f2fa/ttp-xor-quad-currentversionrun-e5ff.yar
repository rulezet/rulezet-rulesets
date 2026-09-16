rule TTP_XOR_QUAD_CurrentVersionRun_e5ff {
  strings:
    $key_e5ff = { b6 90 [2] 92 9e [2] b9 b2 [2] 97 90 [2] 83 8b [2] 8c 91 [2] 92 8c [2] 90 8d [2] 8b 8b [2] 97 8c [2] 8b a3 }

  condition:
    any of them
}