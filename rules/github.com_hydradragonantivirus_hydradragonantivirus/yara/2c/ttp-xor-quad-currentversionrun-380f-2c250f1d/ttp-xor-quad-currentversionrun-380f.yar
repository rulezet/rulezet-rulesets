rule TTP_XOR_QUAD_CurrentVersionRun_380f {
  strings:
    $key_380f = { 6b 60 [2] 4f 6e [2] 64 42 [2] 4a 60 [2] 5e 7b [2] 51 61 [2] 4f 7c [2] 4d 7d [2] 56 7b [2] 4a 7c [2] 56 53 }

  condition:
    any of them
}