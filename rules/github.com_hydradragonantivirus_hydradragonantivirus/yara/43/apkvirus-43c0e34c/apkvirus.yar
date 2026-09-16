rule ApkVirus
{
    meta:
        author = "loopher"
        description = "This is for scan apk yara"
    strings:
        $shell_code = {12  0b  1a  0a  16  01  1a  00  00  00  71  10  3d  04  0c  00  0c  09  71  10  f6  02  09  00  0c  06  39  06  0a  00  1a  09  16  01  1a  09  e4  00  71  20  bf  00  9a  00  11  00  71  00  b1  05  00  00  0c  02  12  01  6e  10  b0  05  02  00  0c  01  12  03  6e  20  af  05  61  00  0c  03  38  06  05  00  6e  10  29  05  06  00  72  10  b3  05  03  00  0c  08  72  20  b5  05  d8  00  0c  07  72  20  b7  05  b7  00  0c  04  1f  04  f7  01  72  10  b4  05  04  00  0c  09  72  20  b7  05  b9  00  0c  09  72  10  b6  05  09  00  0c  00  28  d2  0d  05  1a  09  16  01  6e  10  b2  05  05  00  0c  09  71  20  bf  00  9a  00  28  d1  0d  09  07  95  1a  09  16  01  6e  10  b8  05  05  00  0c  09  71  20  bf  00  9a  00  28  cf  0d  09  07  95  1a  09  16  01  6e  10  27  05  05  00  0c  09  71  20  bf  00  9a  00  28  c3}
        

    condition:
        any of them
}