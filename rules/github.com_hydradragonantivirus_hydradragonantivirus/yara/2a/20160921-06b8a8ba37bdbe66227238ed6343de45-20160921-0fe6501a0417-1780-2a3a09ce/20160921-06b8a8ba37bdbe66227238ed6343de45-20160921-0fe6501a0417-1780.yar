rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_0fe6501a0417_1780 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash3       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash4       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash5       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash6       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash7       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash8       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash9       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash10      = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash11      = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash12      = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash13      = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash14      = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash15      = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash16      = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash17      = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"
    hash18      = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash19      = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash20      = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"
    hash21      = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1  = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(funct" ascii
    $s2  = "on f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"T" ascii
    $s3  = "eturn \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})()" ascii
    $s4  = "),(function f000(){return \"Lp\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000()" ascii
    $s5  = "n \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(fu" ascii
    $s6  = "000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg" ascii
    $s7  = "(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){re" ascii
    $s8  = "(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})" ascii
    $s9  = "tion f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){retur" ascii
    $s10 = "\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}