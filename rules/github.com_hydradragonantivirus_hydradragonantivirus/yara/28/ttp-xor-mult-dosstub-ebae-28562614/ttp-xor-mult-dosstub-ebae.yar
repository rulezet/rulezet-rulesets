rule TTP_XOR_MULT_DOSStub_ebae {
  strings:
    $key_ebae = { bf c6 [2] cb de [2] 8c dc [2] cb cd [2] 85 c1 [2] 89 cb [2] 9e c0 [2] 85 8e [2] b8 }

  condition:
    any of them
}