rule Nush_64___Nessie_C_64__16_lil_72_
{
strings:
	$a0 = { 25ac938a3d242e2687f8f2c4368ea19fc07d296a846dbd3467a215ccfe044ab924dfef40da965f9031d662aa154dcb703375fc4537535ed226a97b1c125fcc4e863cdb2801fcb17c }

condition:
	$a0
}