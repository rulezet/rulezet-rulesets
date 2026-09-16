rule RC5_and_RC6_magic_values__0xb7e15163L_0x9e3779b9L___32_lil_AND_ {
  strings:
    $a0 = { 63 51 e1 b7 [0-20] b9 79 37 9e }

  condition:
    $a0
}