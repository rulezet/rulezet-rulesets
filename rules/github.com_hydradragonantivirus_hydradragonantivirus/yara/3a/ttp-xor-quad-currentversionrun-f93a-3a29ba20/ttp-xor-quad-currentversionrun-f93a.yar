rule TTP_XOR_QUAD_CurrentVersionRun_f93a {
  strings:
    $key_f93a = { aa 55 [2] 8e 5b [2] a5 77 [2] 8b 55 [2] 9f 4e [2] 90 54 [2] 8e 49 [2] 8c 48 [2] 97 4e [2] 8b 49 [2] 97 66 }

  condition:
    any of them
}