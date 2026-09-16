rule TTP_XOR_QUAD_CurrentVersionRun_092f {
  strings:
    $key_092f = { 5a 40 [2] 7e 4e [2] 55 62 [2] 7b 40 [2] 6f 5b [2] 60 41 [2] 7e 5c [2] 7c 5d [2] 67 5b [2] 7b 5c [2] 67 73 }

  condition:
    any of them
}