rule TTP_XOR_QUAD_CurrentVersionRun_121e {
  strings:
    $key_121e = { 41 71 [2] 65 7f [2] 4e 53 [2] 60 71 [2] 74 6a [2] 7b 70 [2] 65 6d [2] 67 6c [2] 7c 6a [2] 60 6d [2] 7c 42 }

  condition:
    any of them
}