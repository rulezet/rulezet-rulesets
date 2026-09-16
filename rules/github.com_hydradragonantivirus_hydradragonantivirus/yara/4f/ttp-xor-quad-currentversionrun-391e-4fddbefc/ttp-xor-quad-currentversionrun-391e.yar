rule TTP_XOR_QUAD_CurrentVersionRun_391e {
  strings:
    $key_391e = { 6a 71 [2] 4e 7f [2] 65 53 [2] 4b 71 [2] 5f 6a [2] 50 70 [2] 4e 6d [2] 4c 6c [2] 57 6a [2] 4b 6d [2] 57 42 }

  condition:
    any of them
}