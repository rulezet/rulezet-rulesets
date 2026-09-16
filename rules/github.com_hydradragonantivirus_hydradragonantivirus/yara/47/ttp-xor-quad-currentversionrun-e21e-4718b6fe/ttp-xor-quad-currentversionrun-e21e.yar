rule TTP_XOR_QUAD_CurrentVersionRun_e21e {
  strings:
    $key_e21e = { b1 71 [2] 95 7f [2] be 53 [2] 90 71 [2] 84 6a [2] 8b 70 [2] 95 6d [2] 97 6c [2] 8c 6a [2] 90 6d [2] 8c 42 }

  condition:
    any of them
}