rule TTP_XOR_QUAD_CurrentVersionRun_093c {
  strings:
    $key_093c = { 5a 53 [2] 7e 5d [2] 55 71 [2] 7b 53 [2] 6f 48 [2] 60 52 [2] 7e 4f [2] 7c 4e [2] 67 48 [2] 7b 4f [2] 67 60 }

  condition:
    any of them
}