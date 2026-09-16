rule snake_packed
{
meta:
author = "artemon security"
md5 = "f4f192004df1a4723cb9a8b4a9eb2fbf"
reference = "http://artemonsecurity.com/uroburos.pdf"
strings:

$cr0 = { 25 FF FF FE FF 0F 22 C0 E8 ?? ?? 00 00}
condition:
any of them
}