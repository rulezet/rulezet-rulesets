rule TTP_XOR_QUAD_CurrentVersionRun_f91f {
  strings:
    $key_f91f = { aa 70 [2] 8e 7e [2] a5 52 [2] 8b 70 [2] 9f 6b [2] 90 71 [2] 8e 6c [2] 8c 6d [2] 97 6b [2] 8b 6c [2] 97 43 }

  condition:
    any of them
}