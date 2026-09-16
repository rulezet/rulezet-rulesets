rule TTP_XOR_QUAD_CurrentVersionRun_090a {
  strings:
    $key_090a = { 5a 65 [2] 7e 6b [2] 55 47 [2] 7b 65 [2] 6f 7e [2] 60 64 [2] 7e 79 [2] 7c 78 [2] 67 7e [2] 7b 79 [2] 67 56 }

  condition:
    any of them
}